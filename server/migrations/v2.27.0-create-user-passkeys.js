const { DataTypes } = require('sequelize')

module.exports = {
  up: async ({ context: queryInterface }) => {
    await queryInterface.createTable('userPasskeys', {
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
      },
      createdAt: {
        type: DataTypes.DATE,
        allowNull: false
      },
      updatedAt: {
        type: DataTypes.DATE,
        allowNull: false
      }
    })
  },
  down: async ({ context: queryInterface }) => {
    await queryInterface.dropTable('userPasskeys')
  }
}
