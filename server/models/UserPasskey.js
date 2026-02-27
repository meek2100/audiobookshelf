const { DataTypes, Model } = require('sequelize')

class UserPasskey extends Model {
  static init(sequelize) {
    super.init(
      {
        id: {
          type: DataTypes.UUID,
          defaultValue: DataTypes.UUIDV4,
          primaryKey: true
        },
        userId: {
          type: DataTypes.UUID,
          allowNull: false,
          references: {
            model: 'users',
            key: 'id'
          },
          onDelete: 'CASCADE'
        },
        credentialID: {
          type: DataTypes.STRING,
          allowNull: false,
          unique: true
        },
        credentialPublicKey: {
          type: DataTypes.BLOB,
          allowNull: false
        },
        counter: {
          type: DataTypes.BIGINT,
          allowNull: false,
          defaultValue: 0
        },
        transports: {
          type: DataTypes.STRING,
          allowNull: true
        },
        deviceType: {
          type: DataTypes.STRING,
          allowNull: false,
          defaultValue: 'singleDevice'
        },
        backedUp: {
          type: DataTypes.BOOLEAN,
          allowNull: false,
          defaultValue: false
        }
      },
      {
        sequelize,
        modelName: 'userPasskey'
      }
    )

    const { user } = sequelize.models
    user.hasMany(UserPasskey, { foreignKey: 'userId', onDelete: 'CASCADE' })
    UserPasskey.belongsTo(user, { foreignKey: 'userId' })
  }
}

module.exports = UserPasskey
